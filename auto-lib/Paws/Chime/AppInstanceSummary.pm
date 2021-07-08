# Generated by default/object.tt
package Paws::Chime::AppInstanceSummary;
  use Moose;
  has AppInstanceArn => (is => 'ro', isa => 'Str');
  has Metadata => (is => 'ro', isa => 'Str');
  has Name => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Chime::AppInstanceSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Chime::AppInstanceSummary object:

  $service_obj->Method(Att1 => { AppInstanceArn => $value, ..., Name => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Chime::AppInstanceSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->AppInstanceArn

=head1 DESCRIPTION

Summary of the data for an C<AppInstance>.

=head1 ATTRIBUTES


=head2 AppInstanceArn => Str

The C<AppInstance> ARN.


=head2 Metadata => Str

The metadata of the C<AppInstance>.


=head2 Name => Str

The name of the C<AppInstance>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Chime>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

