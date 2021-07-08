# Generated by default/object.tt
package Paws::ResourceGroups::Group;
  use Moose;
  has Description => (is => 'ro', isa => 'Str');
  has GroupArn => (is => 'ro', isa => 'Str', required => 1);
  has Name => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ResourceGroups::Group

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ResourceGroups::Group object:

  $service_obj->Method(Att1 => { Description => $value, ..., Name => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ResourceGroups::Group object:

  $result = $service_obj->Method(...);
  $result->Att1->Description

=head1 DESCRIPTION

A resource group that contains AWS resources. You can assign resources
to the group by associating either of the following elements with the
group:

=over

=item *

ResourceQuery - Use a resource query to specify a set of tag keys and
values. All resources in the same AWS Region and AWS account that have
those keys with the same values are included in the group. You can add
a resource query when you create the group, or later by using the
PutGroupConfiguration operation.

=item *

GroupConfiguration - Use a service configuration to associate the group
with an AWS service. The configuration specifies which resource types
can be included in the group.

=back


=head1 ATTRIBUTES


=head2 Description => Str

The description of the resource group.


=head2 B<REQUIRED> GroupArn => Str

The ARN of the resource group.


=head2 B<REQUIRED> Name => Str

The name of the resource group.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ResourceGroups>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

