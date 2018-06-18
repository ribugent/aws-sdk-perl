
package Paws::ELBv2::AddTags;
  use Moose;
  has ResourceArns => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);
  has Tags => (is => 'ro', isa => 'ArrayRef[Paws::ELBv2::Tag]', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'AddTags');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::ELBv2::AddTagsOutput');
  class_has _result_key => (isa => 'Str', is => 'ro', default => 'AddTagsResult');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ELBv2::AddTags - Arguments for method AddTags on L<Paws::ELBv2>

=head1 DESCRIPTION

This class represents the parameters used for calling the method AddTags on the
L<Elastic Load Balancing|Paws::ELBv2> service. Use the attributes of this class
as arguments to method AddTags.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to AddTags.

=head1 SYNOPSIS

    my $elasticloadbalancing = Paws->service('ELBv2');
    # To add tags to a load balancer
    # This example adds the specified tags to the specified load balancer.
    my $AddTagsOutput = $elasticloadbalancing->AddTags(
      {
        'ResourceArns' => [
'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188'
        ],
        'Tags' => [

          {
            'Key'   => 'project',
            'Value' => 'lima'
          },

          {
            'Key'   => 'department',
            'Value' => 'digital-media'
          }
        ]
      }
    );


Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/elasticloadbalancing/AddTags>

=head1 ATTRIBUTES


=head2 B<REQUIRED> ResourceArns => ArrayRef[Str|Undef]

The Amazon Resource Name (ARN) of the resource.



=head2 B<REQUIRED> Tags => ArrayRef[L<Paws::ELBv2::Tag>]

The tags. Each resource can have a maximum of 10 tags.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method AddTags in L<Paws::ELBv2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

